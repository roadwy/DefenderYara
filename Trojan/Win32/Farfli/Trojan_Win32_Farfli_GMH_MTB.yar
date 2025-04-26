
rule Trojan_Win32_Farfli_GMH_MTB{
	meta:
		description = "Trojan:Win32/Farfli.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 83 f9 0c ?? ?? 33 c9 0f b7 d1 8a 54 55 e4 30 14 07 40 41 3b c6 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}