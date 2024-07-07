
rule TrojanProxy_Win32_Poindampa_A{
	meta:
		description = "TrojanProxy:Win32/Poindampa.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 45 46 41 55 4c 54 5f 43 4f 4e 4e 45 43 54 5f 53 54 52 49 4e 47 3d 61 64 73 2e 66 75 73 69 6f 6e 74 72 6b 2e 63 6f 6d 58 58 58 58 58 } //2 DEFAULT_CONNECT_STRING=ads.fusiontrk.comXXXXX
		$a_03_1 = {43 44 43 5f 56 4f 52 44 4d 45 5f 49 4e 53 54 41 4e 43 45 5f 4d 55 54 45 58 5f 90 0f 08 00 90 00 } //2
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 41 70 70 44 6f 6d 61 69 6e 00 52 75 6e 42 65 66 6f 72 65 } //2 潓瑦慷敲䅜灰潄慭湩刀湵敂潦敲
		$a_01_3 = {43 68 65 63 6b 70 6f 69 6e 74 20 65 6e 64 20 6f 66 20 52 65 71 75 65 73 74 48 65 61 64 65 72 73 2e 69 6e 73 65 72 74 28 29 20 63 72 61 70 2e } //1 Checkpoint end of RequestHeaders.insert() crap.
		$a_01_4 = {53 65 72 76 65 72 4c 6f 6f 70 28 29 3a 20 43 6f 6e 6e 65 63 74 69 6f 6e 20 73 75 63 63 65 65 64 65 64 20 69 6d 6d 65 64 69 61 74 65 6c 79 3b 20 57 54 46 3f } //1 ServerLoop(): Connection succeeded immediately; WTF?
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}