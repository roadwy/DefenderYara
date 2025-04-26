
rule TrojanDropper_Win32_FnDialer{
	meta:
		description = "TrojanDropper:Win32/FnDialer,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 74 74 65 72 6e 20 6e 6f 74 20 66 6f 75 6e 64 21 00 46 75 6e 63 74 69 6f 6e 20 6e 6f 74 20 66 6f 75 6e 64 21 00 49 6e 66 6f 00 66 6e 44 69 61 6c 65 72 44 6c 6c } //1 瑡整湲渠瑯映畯摮!畆据楴湯渠瑯映畯摮!湉潦昀䑮慩敬䑲汬
	condition:
		((#a_01_0  & 1)*1) >=1
 
}