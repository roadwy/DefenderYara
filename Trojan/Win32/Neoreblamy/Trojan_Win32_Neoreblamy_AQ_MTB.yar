
rule Trojan_Win32_Neoreblamy_AQ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {51 71 72 62 66 70 44 68 6c 4f 4d 44 51 49 7a 50 78 47 48 45 4a 6a 4f 45 61 45 68 45 61 } //1 QqrbfpDhlOMDQIzPxGHEJjOEaEhEa
		$a_01_1 = {70 46 55 4a 6e 43 7a 76 4c 54 73 43 56 47 6b 57 7a 5a 44 79 74 55 48 78 58 67 5a 64 46 } //1 pFUJnCzvLTsCVGkWzZDytUHxXgZdF
		$a_01_2 = {56 66 48 63 5a 6a 66 66 5a 73 54 50 64 54 57 53 68 72 58 65 4b 68 65 42 61 68 48 67 78 } //1 VfHcZjffZsTPdTWShrXeKheBahHgx
		$a_01_3 = {6e 48 73 6a 5a 6c 70 78 6e 53 43 4d 73 61 73 67 56 41 4a 74 6f } //1 nHsjZlpxnSCMsasgVAJto
		$a_01_4 = {4b 55 74 66 6b 57 63 54 79 7a 46 51 49 74 6a 69 55 51 49 76 63 54 } //1 KUtfkWcTyzFQItjiUQIvcT
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}