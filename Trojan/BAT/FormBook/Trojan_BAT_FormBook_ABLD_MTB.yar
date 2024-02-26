
rule Trojan_BAT_FormBook_ABLD_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABLD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {43 69 6e 65 6d 61 4d 61 6e 61 67 65 72 2e 50 72 6f 70 65 72 74 69 65 73 00 72 65 73 6f 75 72 63 65 } //02 00 
		$a_01_1 = {43 69 6e 65 6d 61 4d 61 6e 61 67 65 72 2e 53 65 6c 6c 54 69 63 6b 65 74 46 6f 72 6d } //02 00  CinemaManager.SellTicketForm
		$a_01_2 = {43 69 6e 65 6d 61 4d 61 6e 61 67 65 72 2e 50 61 79 6d 65 6e 74 46 6f 72 6d } //01 00  CinemaManager.PaymentForm
		$a_01_3 = {43 00 69 00 6e 00 65 00 6d 00 61 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 } //00 00  CinemaManager
	condition:
		any of ($a_*)
 
}