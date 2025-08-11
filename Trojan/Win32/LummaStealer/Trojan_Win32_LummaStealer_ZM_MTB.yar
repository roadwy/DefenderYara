
rule Trojan_Win32_LummaStealer_ZM_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZM!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 36 a1 81 19 57 cf d2 19 57 cf d2 19 57 cf d2 0d 3c cc cd 31 25 7c fd 20 d3 cc ad 39 15 7c fd 20 d3 cc bd 30 b5 7c fd 20 d3 cc ed 31 d5 7c fd 23 e9 1b 4d 21 a5 7c fd 21 95 7c ed 27 b5 7c fd 24 b2 2c ad 30 45 7c fd 24 b2 2c bd 31 65 7c fd 24 b2 2c cd 30 85 7c fd 21 95 7c fd 21 85 7c fd 2d 42 2c fd 31 85 7c fd 2d 42 2c dd 31 85 7c fd 25 26 96 36 81 95 7c fd } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}