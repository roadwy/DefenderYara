
rule Trojan_Win64_Bazarcrypt_GD_MTB{
	meta:
		description = "Trojan:Win64/Bazarcrypt.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 41 f7 [0-02] 8d 1c [0-02] ff 15 [0-04] 44 8a [0-04] 4c 63 [0-02] 49 83 [0-02] 01 41 0f b6 [0-02] 41 02 [0-02] 43 32 [0-04] 48 83 [0-02] 01 41 88 [0-04] 74 09 44 8b [0-06] eb } //5
		$a_80_1 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //GetCurrentProcess  1
		$a_80_2 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //LoadResource  1
	condition:
		((#a_02_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=7
 
}