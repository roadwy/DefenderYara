
rule Trojan_Win32_StealC_BBV_MTB{
	meta:
		description = "Trojan:Win32/StealC.BBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 04 1e 83 ff 0f 75 } //00 00 
	condition:
		any of ($a_*)
 
}