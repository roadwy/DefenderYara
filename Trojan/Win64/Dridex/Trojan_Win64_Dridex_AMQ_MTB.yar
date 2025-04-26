
rule Trojan_Win64_Dridex_AMQ_MTB{
	meta:
		description = "Trojan:Win64/Dridex.AMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_00_0 = {b9 01 00 00 00 8b 54 24 50 81 f2 5e db 74 39 4c 8b 44 24 40 4d 0f af c0 4c 89 44 24 58 39 d0 89 4c 24 30 74 09 } //10
		$a_80_1 = {4e 65 74 53 68 61 72 65 47 65 74 49 6e 66 6f } //NetShareGetInfo  3
		$a_80_2 = {43 72 79 70 74 43 41 54 50 75 74 41 74 74 72 49 6e 66 6f } //CryptCATPutAttrInfo  3
		$a_80_3 = {55 72 6c 55 6e 65 73 63 61 70 65 57 } //UrlUnescapeW  3
		$a_80_4 = {52 70 63 42 69 6e 64 69 6e 67 53 65 74 41 75 74 68 49 6e 66 6f 41 } //RpcBindingSetAuthInfoA  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}