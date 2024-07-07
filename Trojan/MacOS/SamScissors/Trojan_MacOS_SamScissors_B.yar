
rule Trojan_MacOS_SamScissors_B{
	meta:
		description = "Trojan:MacOS/SamScissors.B,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 61 79 6c 6f 61 64 32 2d 35 35 35 35 34 39 34 34 38 33 39 32 31 36 30 34 39 64 36 38 33 30 37 35 62 63 33 66 35 61 38 36 32 38 37 37 38 62 62 38 } //2 payload2-55554944839216049d683075bc3f5a8628778bb8
		$a_01_1 = {33 63 78 5f 61 75 74 68 5f 69 64 3d 25 73 3b 33 63 78 5f 61 75 74 68 5f 74 6f 6b 65 6e 5f 63 6f 6e 74 65 6e 74 3d 25 73 3b 5f 5f 74 75 74 6d 61 3d 74 72 75 65 } //1 3cx_auth_id=%s;3cx_auth_token_content=%s;__tutma=true
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 73 62 6d 73 61 2e 77 69 6b 69 2f 62 6c 6f 67 2f 5f 69 6e 73 65 72 74 } //1 https://sbmsa.wiki/blog/_insert
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}