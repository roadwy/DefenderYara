
rule Worm_Win32_Soltern_GMH_MTB{
	meta:
		description = "Worm:Win32/Soltern.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 55 4b 53 71 4a 6e 62 } //1 dUKSqJnb
		$a_01_1 = {4e 55 64 71 74 4c 71 54 } //1 NUdqtLqT
		$a_01_2 = {45 f0 e8 49 e4 ff ff c3 e9 67 70 ff ff eb f0 8b d6 8b c3 8b cf e8 02 fd ff ff 5f 5e 5b 8b e5 5d } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10) >=12
 
}