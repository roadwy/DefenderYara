
rule Trojan_BAT_Injuke_MB_MTB{
	meta:
		description = "Trojan:BAT/Injuke.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_81_0 = {37 66 33 63 31 63 32 65 2d 65 31 62 36 2d 34 65 32 34 2d 62 38 66 65 2d 34 33 65 64 36 37 35 65 63 66 64 63 } //1 7f3c1c2e-e1b6-4e24-b8fe-43ed675ecfdc
		$a_81_1 = {48 6f 74 73 70 6f 74 20 53 68 69 65 6c 64 20 37 2e 39 2e 30 } //1 Hotspot Shield 7.9.0
		$a_81_2 = {56 74 7a 71 72 73 6b 75 62 74 6e 63 6f 76 73 72 71 64 70 73 78 62 6e 74 } //1 Vtzqrskubtncovsrqdpsxbnt
		$a_81_3 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_81_4 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_81_5 = {43 69 70 68 65 72 4d 6f 64 65 } //1 CipherMode
		$a_81_6 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_81_7 = {43 72 79 70 74 6f 53 74 72 65 61 6d } //1 CryptoStream
		$a_81_8 = {73 65 74 5f 4b 65 79 53 69 7a 65 } //1 set_KeySize
		$a_81_9 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_10 = {70 6f 77 65 72 73 68 65 6c 6c } //1 powershell
		$a_81_11 = {54 65 73 74 2d 43 6f 6e 6e 65 63 74 69 6f 6e } //1 Test-Connection
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=12
 
}