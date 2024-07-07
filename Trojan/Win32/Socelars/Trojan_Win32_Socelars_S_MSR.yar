
rule Trojan_Win32_Socelars_S_MSR{
	meta:
		description = "Trojan:Win32/Socelars.S!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 72 65 61 74 65 69 6e 66 6f 2e 70 77 2f 48 6f 6d 65 2f 49 6e 64 65 78 2f 67 65 74 64 61 74 61 } //2 http://www.createinfo.pw/Home/Index/getdata
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6a 73 78 6a 62 78 78 2e 70 77 } //2 http://www.jsxjbxx.pw
		$a_01_2 = {42 00 69 00 6c 00 6c 00 69 00 6e 00 67 00 54 00 72 00 61 00 6e 00 73 00 61 00 63 00 74 00 69 00 6f 00 6e 00 73 00 44 00 61 00 74 00 61 00 4c 00 6f 00 61 00 64 00 65 00 72 00 } //1 BillingTransactionsDataLoader
		$a_01_3 = {70 61 79 6d 65 6e 74 5f 6d 65 74 68 6f 64 } //1 payment_method
		$a_01_4 = {46 3a 5c 66 61 63 65 62 6f 6f 6b 32 30 31 39 30 35 32 37 5f 6e 65 77 76 65 72 73 69 6f 6e 5c 64 61 74 61 62 61 73 65 5c 52 65 6c 65 61 73 65 5c 44 69 73 6b 53 63 61 6e 2e 70 64 62 } //2 F:\facebook20190527_newversion\database\Release\DiskScan.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2) >=5
 
}