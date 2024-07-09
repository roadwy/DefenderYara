
rule Trojan_Win32_VBKrypt_BG_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 07 00 00 "
		
	strings :
		$a_02_0 = {ff 34 0a 39 c2 [0-4f] 81 f7 [0-1f] 89 3c 08 [0-1f] 83 e9 04 7d [0-1f] ff d0 } //1
		$a_02_1 = {ff 34 0a 39 c1 [0-4f] 81 f7 [0-1f] 89 3c 08 [0-1f] 83 e9 04 7d [0-1f] ff d0 } //1
		$a_02_2 = {ff 34 0a 39 c6 [0-4f] 81 f7 [0-1f] 89 3c 08 [0-1f] 83 e9 04 7d [0-1f] ff d0 } //1
		$a_02_3 = {ff 34 0a 39 c3 [0-4f] 81 f7 [0-1f] 89 3c 08 [0-1f] 83 e9 04 7d [0-1f] ff d0 } //1
		$a_02_4 = {ff 34 0a 39 c7 [0-4f] 81 f7 [0-1f] 89 3c 08 [0-1f] 83 e9 04 7d [0-1f] ff d0 } //1
		$a_02_5 = {ff 34 0a 39 d0 [0-4f] 81 f7 [0-1f] 89 3c 08 [0-1f] 83 e9 04 7d [0-1f] ff d0 } //1
		$a_02_6 = {39 c6 ff 34 0a [0-4f] 81 f7 [0-1f] 89 3c 08 [0-1f] 83 e9 04 7d [0-1f] ff d0 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1+(#a_02_6  & 1)*1) >=1
 
}