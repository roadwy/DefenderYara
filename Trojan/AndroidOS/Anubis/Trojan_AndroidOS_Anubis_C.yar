
rule Trojan_AndroidOS_Anubis_C{
	meta:
		description = "Trojan:AndroidOS/Anubis.C,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {2f 6f 31 6f 2f 61 31 2e 70 68 70 } //02 00  /o1o/a1.php
		$a_00_1 = {66 61 66 64 68 61 73 73 64 2e 69 6e } //02 00  fafdhassd.in
		$a_00_2 = {69 6e 74 65 72 76 61 6c 4c 6f 63 6b 49 6e 6a 54 69 6d 65 } //02 00  intervalLockInjTime
		$a_00_3 = {70 65 72 65 68 76 61 74 5f 73 77 73 } //00 00  perehvat_sws
	condition:
		any of ($a_*)
 
}