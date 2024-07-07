
rule TrojanProxy_Win32_Nvgra_gen_A{
	meta:
		description = "TrojanProxy:Win32/Nvgra.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {75 27 83 bd 7c ff ff ff 7c 75 1e b9 1f 00 00 00 8d 75 84 8b 7d 08 f3 a5 } //1
		$a_01_1 = {8b 55 fc 33 c0 8a 42 02 83 f8 05 75 16 8b 4d fc 8b 51 04 89 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}