
rule Trojan_Win32_Exchrom_B{
	meta:
		description = "Trojan:Win32/Exchrom.B,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_01_0 = {80 c2 0f f6 d2 fe ca f6 d2 2a d0 80 ea 25 f6 d2 80 ea 1d 80 f2 e8 80 ea 06 80 f2 aa f6 d2 02 d0 f6 d2 32 d0 80 f2 eb } //5
		$a_03_1 = {68 f4 01 00 00 ff d3 6a 00 be ?? ?? ?? 00 e8 ?? ?? ff ff 83 c4 04 68 e0 2e 00 00 ff d3 } //4
		$a_01_2 = {68 74 74 70 3a 2f 2f 25 73 2f 63 70 70 2f 73 74 61 74 65 } //2 http://%s/cpp/state
		$a_01_3 = {68 74 74 70 3a 2f 2f 25 73 2f 63 70 70 2f 61 70 70 2e 63 72 78 } //2 http://%s/cpp/app.crx
		$a_01_4 = {66 69 6c 6d 70 69 6b 61 2e 63 6f 6d } //1 filmpika.com
		$a_01_5 = {6b 65 74 61 6e 74 2e 6e 65 74 } //1 ketant.net
		$a_01_6 = {62 61 6b 73 74 6f 72 61 6e 2e 63 6f 6d } //1 bakstoran.com
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*4+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=10
 
}