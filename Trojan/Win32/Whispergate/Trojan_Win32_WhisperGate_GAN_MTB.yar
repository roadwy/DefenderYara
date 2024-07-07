
rule Trojan_Win32_WhisperGate_GAN_MTB{
	meta:
		description = "Trojan:Win32/WhisperGate.GAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 c8 0f b6 00 89 c3 8b 45 e4 89 c1 c1 f9 1f 83 e1 03 01 c8 c1 f8 02 01 d8 88 02 8b 45 e8 8d 50 01 8b 45 dc 8d 0c 02 8b 45 e4 99 c1 ea 1e 01 d0 83 e0 03 29 d0 c1 e0 06 88 01 83 45 e8 02 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}