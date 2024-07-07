
rule Trojan_Win32_OnLineGameHijack_ibt{
	meta:
		description = "Trojan:Win32/OnLineGameHijack!ibt,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {7b 42 38 35 39 32 31 30 33 2d 41 45 38 43 2d 34 44 33 37 2d 38 30 37 46 2d 46 31 43 42 37 36 45 36 32 42 37 43 7d } //1 {B8592103-AE8C-4D37-807F-F1CB76E62B7C}
		$a_01_1 = {ff 15 00 41 0e 10 8b f8 85 ff 74 6b 6a 04 68 00 30 00 00 ff b5 5c f2 ff ff 6a 00 53 ff 15 44 40 0e 10 8b f0 85 f6 74 49 83 bd 60 f2 ff ff 10 8d 8d 4c f2 ff ff 6a 00 ff b5 5c f2 ff ff 0f 43 8d 4c f2 ff ff 51 56 53 ff 15 48 40 0e 10 85 c0 74 20 6a 00 6a 00 56 57 6a 00 6a 00 53 ff 15 4c 40 0e 10 8b 35 ec 40 0e 10 85 c0 74 0b 50 ff d6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}