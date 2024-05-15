
rule Trojan_Win32_LummaStealer_NME_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.NME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {32 37 3e 34 90 01 01 83 c4 04 5b 69 8d 90 01 04 fe 00 00 00 81 c1 3b 66 f3 56 69 95 90 01 04 fe 00 00 00 90 00 } //03 00 
		$a_03_1 = {49 4c 39 4f 90 01 01 3e 4c 39 37 45 83 c4 90 01 01 5b 8b 8d 84 fd ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}