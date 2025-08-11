
rule Trojan_Win32_Razy_PGRZ_MTB{
	meta:
		description = "Trojan:Win32/Razy.PGRZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 3f 75 75 3d 75 3f f4 d6 75 3d 1b 75 75 75 5a 1f 6e 24 3f 4a 1f 3d f4 7d 75 3d f4 75 9d 6e 75 80 02 00 00 bd 75 97 bd 3f ac a9 01 91 25 76 86 91 cd 73 a5 a5 2d a4 b6 ea 02 08 18 9b 81 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}