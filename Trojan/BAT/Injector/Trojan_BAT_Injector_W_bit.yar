
rule Trojan_BAT_Injector_W_bit{
	meta:
		description = "Trojan:BAT/Injector.W!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {08 07 8e b7 5d 0d 02 08 02 08 91 07 09 91 61 9c 08 17 58 0c } //2
		$a_01_1 = {49 00 4e 00 53 00 45 00 52 00 54 00 20 00 49 00 4e 00 54 00 4f 00 20 00 65 00 6d 00 70 00 6c 00 6f 00 79 00 65 00 65 00 28 00 45 00 6d 00 70 00 6c 00 6f 00 79 00 65 00 65 00 20 00 4e 00 61 00 6d 00 65 00 2c 00 20 00 49 00 43 00 20 00 4e 00 75 00 6d 00 62 00 65 00 72 00 2c 00 20 00 48 00 50 00 20 00 4e 00 75 00 6d 00 62 00 65 00 72 00 2c 00 20 00 41 00 64 00 64 00 72 00 65 00 73 00 73 00 29 00 20 00 56 00 61 00 6c 00 75 00 65 00 73 00 20 00 28 00 27 00 } //2 INSERT INTO employee(Employee Name, IC Number, HP Number, Address) Values ('
		$a_01_2 = {63 00 3a 00 5c 00 74 00 65 00 73 00 74 00 5c 00 43 00 6f 00 6e 00 74 00 61 00 63 00 74 00 73 00 2e 00 74 00 78 00 74 00 } //1 c:\test\Contacts.txt
		$a_01_3 = {63 00 3a 00 5c 00 74 00 65 00 73 00 74 00 5c 00 43 00 6f 00 6e 00 74 00 61 00 63 00 74 00 73 00 52 00 65 00 70 00 6f 00 72 00 74 00 2e 00 74 00 78 00 74 00 } //1 c:\test\ContactsReport.txt
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}