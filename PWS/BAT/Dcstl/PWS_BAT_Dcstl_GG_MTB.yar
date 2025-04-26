
rule PWS_BAT_Dcstl_GG_MTB{
	meta:
		description = "PWS:BAT/Dcstl.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 08 00 00 "
		
	strings :
		$a_80_0 = {52 6f 61 6d 69 6e 67 5c 44 69 73 63 6f 72 64 } //Roaming\Discord  10
		$a_80_1 = {5b 5c 77 2d 5d 7b 32 34 7d 5c 2e 5b 5c 77 2d 5d 7b 36 7d 5c 2e 5b 5c 77 2d 5d 7b 32 37 7d } //[\w-]{24}\.[\w-]{6}\.[\w-]{27}  10
		$a_80_2 = {6d 66 61 5c 2e 5b 5c 77 2d 5d 7b 38 34 7d } //mfa\.[\w-]{84}  10
		$a_80_3 = {4c 6f 63 61 6c 5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 } //Local\Google\Chrome\User Data\Default  1
		$a_80_4 = {52 6f 61 6d 69 6e 67 5c 4f 70 65 72 61 20 53 6f 66 74 77 61 72 65 5c 4f 70 65 72 61 20 53 74 61 62 6c 65 } //Roaming\Opera Software\Opera Stable  1
		$a_80_5 = {4c 6f 63 61 6c 5c 42 72 61 76 65 53 6f 66 74 77 61 72 65 5c 42 72 61 76 65 2d 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 } //Local\BraveSoftware\Brave-Browser\User Data\Default  1
		$a_80_6 = {5c 41 70 70 44 61 74 61 5c } //\AppData\  1
		$a_80_7 = {5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 6c 65 76 65 6c 64 62 } //\Local Storage\leveldb  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*10+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=33
 
}