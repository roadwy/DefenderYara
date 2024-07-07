
rule Trojan_Win32_Midie_GMH_MTB{
	meta:
		description = "Trojan:Win32/Midie.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 64 24 00 8a 14 39 80 ea 24 80 f2 25 88 14 39 41 3b c8 } //10
		$a_01_1 = {42 6f 75 64 6c 65 5f 66 74 70 32 } //1 Boudle_ftp2
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}