
rule Trojan_Win32_Gozi_NT_MTB{
	meta:
		description = "Trojan:Win32/Gozi.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 14 18 8a 1b 0f b6 ca 80 ea 41 0f b6 fb 80 fa 19 8d 41 20 0f b7 f0 8b c1 0f 47 f0 80 eb 41 8d 47 20 80 fb 19 0f b7 c8 8b c7 0f 47 c8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}