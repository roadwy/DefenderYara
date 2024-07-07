
rule TrojanSpy_Win32_Ursnif_gen_A{
	meta:
		description = "TrojanSpy:Win32/Ursnif.gen!A,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 6f 66 74 3d 25 75 26 76 65 72 73 69 6f 6e 3d 25 75 26 75 73 65 72 3d 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 26 73 65 72 76 65 72 3d 25 75 26 69 64 3d 25 75 26 63 72 63 3d 25 78 } //3 soft=%u&version=%u&user=%08x%08x%08x%08x&server=%u&id=%u&crc=%x
		$a_01_1 = {40 53 4f 43 4b 53 3d 2a 40 } //2 @SOCKS=*@
		$a_01_2 = {54 6f 72 43 6c 69 65 6e 74 } //1 TorClient
		$a_01_3 = {54 6f 72 43 72 63 } //1 TorCrc
		$a_01_4 = {2e 6f 6e 69 6f 6e 2f } //1 .onion/
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=10
 
}