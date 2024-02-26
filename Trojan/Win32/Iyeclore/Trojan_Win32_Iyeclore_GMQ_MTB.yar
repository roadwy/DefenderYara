
rule Trojan_Win32_Iyeclore_GMQ_MTB{
	meta:
		description = "Trojan:Win32/Iyeclore.GMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {2d 46 31 37 34 31 31 38 33 36 36 32 35 7d 00 00 00 } //01 00 
		$a_01_1 = {24 49 65 78 70 6c 63 72 65 } //00 00  $Iexplcre
	condition:
		any of ($a_*)
 
}