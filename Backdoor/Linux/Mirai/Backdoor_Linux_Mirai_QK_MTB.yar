
rule Backdoor_Linux_Mirai_QK_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.QK!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {67 65 28 7c 60 61 7b 28 69 66 6c 28 6e 7d 7c 7d 7a 6d 28 6a 67 7c 66 6d 7c 7b 28 6e 7a 67 65 28 7d 7b 26 28 4b 67 66 7c 69 6b 7c 32 28 60 67 7a 7b 6d 48 7a 61 7b 6d 7d 78 26 66 6d 7c 28 7f 61 7c 60 28 5c 70 41 4c 28 69 66 6c 28 41 58 28 5a 69 66 6f 6d 27 49 5b 46 26 08 } //1 敧簨慠⡻晩⡬絮絼浺樨籧浦筼渨杺⡥筽⠦杋籦歩㉼怨穧浻穈筡絭♸浦⡼慿恼尨䅰⡌晩⡬塁娨晩浯䤧䙛ࠦ
		$a_01_1 = {e8 ea fb 8f 80 c8 ca c0 c6 df 80 90 cd ce dd ca 8f e7 fb fb ff 80 9e 81 9f a2 a5 ec c0 c1 c1 ca cc db c6 c0 c1 95 8f cc c3 c0 dc ca a2 a5 a2 a5 a2 af 00 00 71 6a 79 76 71 6b 6c 6a 79 6b 70 36 74 71 7a 6a 7d 64 7b 70 6d 6a 7b 70 77 7e 70 77 74 74 61 6f 77 77 7c 36 74 71 7a 6a 7d 64 71 7f 6d 7d 6b 6b 71 75 70 7d 6a 7d 36 74 71 7a 6a 7d 18 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}