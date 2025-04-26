
rule Trojan_Win64_Dridex_ACD_MTB{
	meta:
		description = "Trojan:Win64/Dridex.ACD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 06 00 00 "
		
	strings :
		$a_00_0 = {c9 e7 70 80 e3 a5 83 15 2e 59 43 9a 38 f7 ac b7 32 f0 ac b3 e3 7a 5c bf c2 e0 fc 6c 0e cd d9 71 } //10
		$a_80_1 = {4d 70 72 41 64 6d 69 6e 49 6e 74 65 72 66 61 63 65 54 72 61 6e 73 70 6f 72 74 41 64 64 } //MprAdminInterfaceTransportAdd  3
		$a_80_2 = {4e 64 72 55 73 65 72 4d 61 72 73 68 61 6c 55 6e 6d 61 72 73 68 61 6c 6c } //NdrUserMarshalUnmarshall  3
		$a_80_3 = {52 70 63 42 69 6e 64 69 6e 67 53 65 74 41 75 74 68 49 6e 66 6f 41 } //RpcBindingSetAuthInfoA  3
		$a_80_4 = {47 65 74 55 72 6c 43 61 63 68 65 45 6e 74 72 79 49 6e 66 6f 57 } //GetUrlCacheEntryInfoW  3
		$a_80_5 = {48 49 43 4f 4e 5f 55 73 65 72 4d 61 72 73 68 61 6c } //HICON_UserMarshal  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3) >=25
 
}