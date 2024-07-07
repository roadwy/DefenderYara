
rule Trojan_Win32_Locky_GK_MTB{
	meta:
		description = "Trojan:Win32/Locky.GK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {7c 44 8b 6c 24 14 03 6c 24 04 8b 74 24 1c 03 34 24 8a 6d 00 8a 0e 31 f6 31 f6 31 f6 30 cd 30 cd 30 cd 88 6d 00 8b 1c 24 43 89 1c 24 8b 1c 24 8b 7c 24 20 4f 39 fb 7e 07 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}