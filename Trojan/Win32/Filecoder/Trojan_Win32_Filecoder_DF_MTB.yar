
rule Trojan_Win32_Filecoder_DF_MTB{
	meta:
		description = "Trojan:Win32/Filecoder.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 01 8d 49 01 04 2a 34 2a 04 2a 34 2a 88 41 ff 83 ea 01 75 } //00 00 
	condition:
		any of ($a_*)
 
}