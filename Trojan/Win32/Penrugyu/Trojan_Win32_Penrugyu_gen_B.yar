
rule Trojan_Win32_Penrugyu_gen_B{
	meta:
		description = "Trojan:Win32/Penrugyu.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {8a 0c 30 80 f1 78 88 0c 30 40 3b c3 7c f2 } //2
		$a_01_1 = {8a c1 b3 03 f6 eb 8a 1c 31 8b d1 81 e2 ff 00 00 00 8a 54 14 0c 32 d0 32 da 88 1c 31 41 3b cf 72 df } //2
		$a_01_2 = {41 63 74 69 6f 6e 3d 25 73 26 53 65 73 73 69 6f 6e 49 44 3d 25 73 26 54 79 70 65 3d 42 61 73 65 36 34 26 50 61 72 61 31 3d 25 73 26 50 61 72 61 32 3d 25 73 26 53 69 7a 65 3d 25 64 26 42 6f 64 79 3d 25 73 } //1 Action=%s&SessionID=%s&Type=Base64&Para1=%s&Para2=%s&Size=%d&Body=%s
		$a_01_3 = {67 72 6f 75 70 65 6e 76 33 32 2e 64 6c 6c 00 } //1
		$a_01_4 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 52 61 73 41 75 74 6f } //1 SYSTEM\CurrentControlSet\Services\RasAuto
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}