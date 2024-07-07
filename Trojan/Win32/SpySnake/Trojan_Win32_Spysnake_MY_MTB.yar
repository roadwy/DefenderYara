
rule Trojan_Win32_Spysnake_MY_MTB{
	meta:
		description = "Trojan:Win32/Spysnake.MY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c4 10 33 c9 39 5d 10 76 17 8b c1 99 6a 0c 5f f7 ff 8a 82 38 e7 40 00 30 04 0e 41 3b 4d 10 72 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}