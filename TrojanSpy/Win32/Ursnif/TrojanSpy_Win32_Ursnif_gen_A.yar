
rule TrojanSpy_Win32_Ursnif_gen_A{
	meta:
		description = "TrojanSpy:Win32/Ursnif.gen!A,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 05 00 00 03 00 "
		
	strings :
		$a_01_0 = {73 6f 66 74 3d 25 75 26 76 65 72 73 69 6f 6e 3d 25 75 26 75 73 65 72 3d 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 26 73 65 72 76 65 72 3d 25 75 26 69 64 3d 25 75 26 63 72 63 3d 25 78 } //02 00  soft=%u&version=%u&user=%08x%08x%08x%08x&server=%u&id=%u&crc=%x
		$a_01_1 = {40 53 4f 43 4b 53 3d 2a 40 } //01 00  @SOCKS=*@
		$a_01_2 = {54 6f 72 43 6c 69 65 6e 74 } //01 00  TorClient
		$a_01_3 = {54 6f 72 43 72 63 } //01 00  TorCrc
		$a_01_4 = {2e 6f 6e 69 6f 6e 2f } //00 00  .onion/
		$a_01_5 = {00 5d 04 00 00 } //36 5f 
	condition:
		any of ($a_*)
 
}