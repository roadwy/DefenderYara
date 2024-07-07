
rule TrojanDownloader_O97M_AgentTesla_BK_MTB{
	meta:
		description = "TrojanDownloader:O97M/AgentTesla.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 5e 69 5e 4e 5e 67 5e 2e 5e 65 5e 58 5e 45 } //1 p^i^N^g^.^e^X^E
		$a_01_1 = {5e 68 5e 74 5e 74 5e 70 5e 73 5e 3a 5e 2f 5e 2f 5e 63 5e 61 5e 6e 5e 61 5e 64 5e 61 5e 63 5e 69 5e 67 5e 61 5e 72 5e 73 5e 75 5e 70 5e 70 5e 6c 5e 69 5e 65 5e 73 5e 2e 5e 63 5e 6f 5e 6d 5e 2f 5e 77 5e 70 5e 2d 5e 63 5e 6f 5e 6e 5e 74 5e 65 5e 6e 5e 74 5e 2f 5e 75 5e 70 5e 6c 5e 6f 5e 61 5e 64 5e 73 5e 2f 5e 32 5e 30 5e 31 5e 38 5e 2f 5e 30 5e 35 5e 2f 5e 66 5e 69 5e 6c 5e 65 5e 73 5e 2f 5e 61 5e 6e 5e 6f 5e 2e 5e 65 5e 78 5e 65 } //1 ^h^t^t^p^s^:^/^/^c^a^n^a^d^a^c^i^g^a^r^s^u^p^p^l^i^e^s^.^c^o^m^/^w^p^-^c^o^n^t^e^n^t^/^u^p^l^o^a^d^s^/^2^0^1^8^/^0^5^/^f^i^l^e^s^/^a^n^o^.^e^x^e
		$a_01_2 = {25 54 45 4d 50 25 5e 5c 5e 66 5e 69 5e 6c 5e 65 5e 73 5e 2e 5e 65 5e 78 5e 65 } //1 %TEMP%^\^f^i^l^e^s^.^e^x^e
		$a_01_3 = {73 5e 74 5e 61 5e 72 5e 74 5e 20 20 20 5e 20 20 20 5e 20 20 20 25 54 45 4d 50 25 5e 5c 5e 66 5e 69 5e 6c 5e 65 5e 73 5e 2e 5e 65 5e 78 5e 65 } //1 s^t^a^r^t^   ^   ^   %TEMP%^\^f^i^l^e^s^.^e^x^e
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_AgentTesla_BK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/AgentTesla.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {78 20 3d 20 58 4f 52 44 65 63 72 79 70 74 69 6f 6e 28 22 61 73 22 2c 20 22 30 33 30 45 30 34 30 34 30 31 } //1 x = XORDecryption("as", "030E040401
		$a_01_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 57 61 69 74 20 28 4e 6f 77 20 2b 20 54 69 6d 65 56 61 6c 75 65 28 22 30 3a 30 30 3a 30 35 22 29 29 } //1 Application.Wait (Now + TimeValue("0:00:05"))
		$a_01_2 = {3d 20 56 61 6c 28 22 26 48 22 20 26 20 28 4d 69 64 24 28 44 61 74 61 49 6e 2c 20 28 32 20 2a 20 6c 6f 6e 44 61 74 61 50 74 72 29 20 2d 20 31 2c 20 32 29 29 29 } //1 = Val("&H" & (Mid$(DataIn, (2 * lonDataPtr) - 1, 2)))
		$a_01_3 = {3d 20 73 74 72 44 61 74 61 4f 75 74 20 2b 20 43 68 72 28 69 6e 74 58 4f 72 56 61 6c 75 65 31 20 58 6f 72 20 69 6e 74 58 4f 72 56 61 6c 75 65 32 29 } //1 = strDataOut + Chr(intXOrValue1 Xor intXOrValue2)
		$a_01_4 = {3d 20 41 73 63 28 4d 69 64 24 28 22 61 73 22 2c 20 28 28 6c 6f 6e 44 61 74 61 50 74 72 20 4d 6f 64 20 4c 65 6e 28 22 61 73 22 29 29 20 2b 20 31 29 2c 20 31 29 29 } //1 = Asc(Mid$("as", ((lonDataPtr Mod Len("as")) + 1), 1))
		$a_01_5 = {53 68 65 6c 6c 20 28 73 74 72 44 61 74 61 4f 75 74 29 } //1 Shell (strDataOut)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}