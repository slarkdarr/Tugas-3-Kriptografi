package com.fsck.k9.ui.settings.account

import android.content.Context
import android.graphics.drawable.Drawable
import android.util.AttributeSet
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.Spinner

import com.fsck.k9.Account
import com.fsck.k9.ui.R

import kotlinx.android.synthetic.main.account_list_item.view.*

class AccountSelectionSpinner : Spinner {
    var selection: Account
        get() = selectedItem as Account
        set(value) {
            selectedAccount = value
            val adapter = adapter as AccountsAdapter
            Spinner@setSelection(adapter.getPosition(value), false)
        }

    private val cachedBackground: Drawable
    private var selectedAccount = Account("")

    constructor(context: Context) : super(context)
    constructor(context: Context, attrs: AttributeSet) : super(context, attrs)

    init {
        adapter = AccountsAdapter(context)
        cachedBackground = background
    }

    public fun setTitle(title: CharSequence) {
        val adapter = adapter as AccountsAdapter
        adapter.title = title
        adapter.notifyDataSetChanged()
    }

    public fun setAccounts(accounts: List<Account>) {
        val adapter = adapter as AccountsAdapter
        adapter.clear()
        adapter.addAll(accounts)
        selection = selectedAccount

        setEnabled(accounts.size > 1)
        background = if (accounts.size > 1) cachedBackground else null
    }

    internal class AccountsAdapter(context: Context) : ArrayAdapter<Account>(context, 0)  {
        var title: CharSequence = ""

        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
            val account = getItem(position)

            val view = convertView
                ?: LayoutInflater.from(context).inflate(R.layout.account_spinner_item, parent, false)

            return view.apply {
                name.text = AccountsAdapter@title
                email.text = account.email
            }
        }

        override fun getDropDownView(position: Int, convertView: View?, parent: ViewGroup): View {
            val account = getItem(position)

            val view = convertView
                ?: LayoutInflater.from(context).inflate(R.layout.account_spinner_dropdown_item, parent, false)

            return view.apply {
                name.text = account.description
                email.text = account.email
            }
        }
    }
}
