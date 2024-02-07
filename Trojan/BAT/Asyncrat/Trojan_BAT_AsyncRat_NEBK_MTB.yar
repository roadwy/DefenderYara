
rule Trojan_BAT_AsyncRat_NEBK_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {66 65 72 65 72 67 72 65 74 66 64 67 72 74 34 35 79 34 35 79 34 35 79 34 35 79 72 74 67 72 67 } //05 00  ferergretfdgrt45y45y45y45yrtgrg
		$a_01_1 = {70 65 74 72 6f 6c 6d 61 6e 61 67 65 6d 65 6e 74 73 79 73 74 65 6d 2e 53 75 70 70 6c 69 65 72 5f 77 69 74 68 64 72 61 77 5f 70 75 6d 70 5f 62 61 6e 6b 5f 64 65 74 61 69 6c 2e 72 65 73 6f 75 72 63 65 73 } //01 00  petrolmanagementsystem.Supplier_withdraw_pump_bank_detail.resources
		$a_01_2 = {52 50 46 3a 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 } //00 00  RPF:SmartAssembly
	condition:
		any of ($a_*)
 
}