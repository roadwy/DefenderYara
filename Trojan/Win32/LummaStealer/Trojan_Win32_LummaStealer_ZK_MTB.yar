
rule Trojan_Win32_LummaStealer_ZK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 39 e7 25 ca 8c f5 b2 45 37 4d f7 95 a6 c3 22 c0 24 0f c9 d0 08 a4 65 f9 a9 bd de 72 84 81 fe 85 cc 7b 61 48 86 a1 0f ad 61 ef b9 21 cd 32 1f c5 b7 e9 a3 4f 86 6b 9d 15 bd 08 d7 be 4f 09 56 23 7f bd 25 9c cf 05 0d e2 2b 8c 1b 55 6e 2a 32 3a a6 d6 f4 44 92 6d 61 47 a4 d2 ca fb 7f 9c dc 5d a1 ce 41 03 b9 a3 ce 1a 56 bd 4d 0a ef a3 64 46 3b cb ac 4c 1c 20 e7 5c a0 68 14 59 33 d9 56 af 48 4e 36 99 a7 09 31 65 73 8a 47 7e 7e b0 97 dd d9 55 26 89 13 49 20 4c da a8 1a 7a d3 c0 26 c9 e9 36 7c 6a 68 e2 f3 f5 04 d8 ec fd 6f 87 0f da 43 3f f7 7c 71 0b c8 27 47 4c f9 a9 c4 0b f5 93 f3 6f d1 05 27 df 5d ae be 3d 6b ac 6a 8e 8c e3 04 a2 9e cb 28 ee 89 d6 2b b6 f1 e3 43 d6 c2 cb b9 89 0d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}