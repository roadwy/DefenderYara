
rule Trojan_Win32_Zapchast_GZZ_MTB{
	meta:
		description = "Trojan:Win32/Zapchast.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {38 2c 38 33 38 45 38 64 38 76 } //05 00  8,838E8d8v
		$a_01_1 = {10 3f 20 3f 32 3f 3a 3f 46 3f 58 3f } //00 00  㼐㼠㼲㼺㽆㽘
	condition:
		any of ($a_*)
 
}