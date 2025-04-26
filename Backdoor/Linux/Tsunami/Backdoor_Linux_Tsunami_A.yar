
rule Backdoor_Linux_Tsunami_A{
	meta:
		description = "Backdoor:Linux/Tsunami.A,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {54 53 55 4e 41 4d 49 20 3c 74 61 72 67 65 74 3e 20 3c 73 65 63 73 3e } //1 TSUNAMI <target> <secs>
		$a_01_1 = {4e 4f 54 49 43 45 20 25 73 20 3a 4b 61 69 74 65 6e 20 77 61 20 67 6f 72 61 6b 75 } //1 NOTICE %s :Kaiten wa goraku
		$a_01_2 = {4e 49 43 4b 20 25 73 5c 6e 55 53 45 52 20 25 73 20 6c 6f 63 61 6c 68 6f 73 74 20 6c 6f 63 61 6c 68 6f 73 74 20 3a 25 73 } //1 NICK %s\nUSER %s localhost localhost :%s
		$a_01_3 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 34 2e 37 35 20 5b 65 6e 5d 20 28 58 31 31 3b 20 55 3b 20 4c 69 6e 75 78 20 32 2e 32 2e 31 36 2d 33 20 69 36 38 36 29 } //1 User-Agent: Mozilla/4.75 [en] (X11; U; Linux 2.2.16-3 i686)
		$a_01_4 = {0f af f1 b9 7b 51 c3 b8 89 f0 f7 e9 89 d0 8d 04 30 89 c1 c1 e9 1f c1 f8 0f 8d 04 08 69 c0 5a b1 00 00 } //3
		$a_01_5 = {0f af c8 c7 85 ac fb ff ff 7b 51 c3 b8 8b 85 ac fb ff ff f7 e9 8d 04 0a 89 c2 c1 fa 0f 89 c8 c1 f8 1f 89 d3 29 c3 } //3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3) >=5
 
}