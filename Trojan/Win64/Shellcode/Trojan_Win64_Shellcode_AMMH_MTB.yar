
rule Trojan_Win64_Shellcode_AMMH_MTB{
	meta:
		description = "Trojan:Win64/Shellcode.AMMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 01 d0 44 0f b6 00 8b 85 90 01 04 48 98 0f b6 4c 05 90 01 01 8b 85 90 01 04 90 02 0b 48 01 d0 44 89 c2 31 ca 88 10 83 85 90 01 04 01 83 85 90 01 04 01 8b 85 90 01 04 48 98 48 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}