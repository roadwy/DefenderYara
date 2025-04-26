
rule Trojan_Win32_Qakbot_CREL_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.CREL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {50 3c 44 69 73 70 6f 73 65 3e 40 45 78 63 65 70 74 69 6f 6e 40 50 6c 61 74 66 6f 72 6d 40 40 55 24 41 41 41 58 58 5a } //1 P<Dispose>@Exception@Platform@@U$AAAXXZ
		$a_01_1 = {50 3f 30 41 74 74 72 69 62 75 74 65 40 4d 65 74 61 64 61 74 61 40 50 6c 61 74 66 6f 72 6d 40 40 51 24 41 41 41 40 58 5a } //1 P?0Attribute@Metadata@Platform@@Q$AAA@XZ
		$a_01_2 = {50 3f 30 43 4f 4d 45 78 63 65 70 74 69 6f 6e 40 50 6c 61 74 66 6f 72 6d 40 40 51 24 41 41 41 40 48 50 24 41 41 56 53 74 72 69 6e 67 40 31 40 40 5a } //1 P?0COMException@Platform@@Q$AAA@HP$AAVString@1@@Z
		$a_01_3 = {50 3f 30 4f 75 74 4f 66 4d 65 6d 6f 72 79 45 78 63 65 70 74 69 6f 6e 40 50 6c 61 74 66 6f 72 6d 40 40 51 24 41 41 41 40 58 5a } //1 P?0OutOfMemoryException@Platform@@Q$AAA@XZ
		$a_01_4 = {50 3f 30 69 6e 74 33 32 40 64 65 66 61 75 6c 74 40 40 51 41 41 40 48 40 5a } //1 P?0int32@default@@QAA@H@Z
		$a_01_5 = {50 47 65 74 48 61 73 68 43 6f 64 65 40 41 74 74 72 69 62 75 74 65 40 4d 65 74 61 64 61 74 61 40 50 6c 61 74 66 6f 72 6d 40 40 51 24 41 41 41 48 58 5a } //1 PGetHashCode@Attribute@Metadata@Platform@@Q$AAAHXZ
		$a_01_6 = {54 65 73 74 } //10 Test
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*10) >=16
 
}