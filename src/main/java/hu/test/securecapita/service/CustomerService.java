package hu.test.securecapita.service;

import hu.test.securecapita.domain.Customer;
import hu.test.securecapita.domain.Invoice;
import org.springframework.data.domain.Page;

public interface CustomerService {
    //Customer functions
    Customer createCustomer(Customer customer);
    Customer updateCustomer(Customer customer);
    Page<Customer> getCustomers(int page, int size);
    Iterable<Customer> getCustomers();
    Customer getCustomer(Long id);
    Page<Customer> searchCustomers(String name, int page, int size);

    //Invoice functions
    Invoice createInvoice(Invoice invoice);
    Page<Invoice> getInvoices(int page, int size);
    void addInvoiceToCustomer(Long id, Invoice invoice);

    Invoice getInvoice(Long id);
}
