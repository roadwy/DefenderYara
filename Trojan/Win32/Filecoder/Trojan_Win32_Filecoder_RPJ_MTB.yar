
rule Trojan_Win32_Filecoder_RPJ_MTB{
	meta:
		description = "Trojan:Win32/Filecoder.RPJ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {ba 97 00 00 00 8a 06 90 32 c2 90 88 07 90 46 90 47 90 } //00 00 
	condition:
		any of ($a_*)
 
}