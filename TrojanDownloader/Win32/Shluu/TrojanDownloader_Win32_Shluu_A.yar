
rule TrojanDownloader_Win32_Shluu_A{
	meta:
		description = "TrojanDownloader:Win32/Shluu.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {c1 e2 10 0b d0 8b 44 24 14 0f af ca 0f af c8 0f af c8 33 d2 bf 19 00 00 00 8b c1 f7 f7 8b 74 24 20 83 cf ff 80 c2 61 88 16 } //2
		$a_01_1 = {49 73 55 73 65 72 41 64 6d 69 6e 00 73 65 74 75 70 61 70 69 2e 64 6c 6c } //1 獉獕牥摁業n敳畴慰楰搮汬
		$a_01_2 = {f6 04 24 09 74 0d 68 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}