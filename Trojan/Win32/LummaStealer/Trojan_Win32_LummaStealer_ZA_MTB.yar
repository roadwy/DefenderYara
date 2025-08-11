
rule Trojan_Win32_LummaStealer_ZA_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 2c a5 bb 2b 97 3d ba 89 d4 65 8e cb 3b db e5 39 1d 90 c4 de 39 6f b3 cd 63 bd a5 a8 85 f0 4c 98 aa 97 1b 50 d5 05 e6 c3 39 f3 33 66 76 b9 e2 bf 28 27 75 5b be b0 7d 98 4a b3 f2 d4 46 3b ff 19 27 c8 15 8a 4f 07 22 ec cc 7b 67 39 16 1f 0e 83 cf 84 6f 7a e4 47 5b 60 b3 3d 91 d4 b2 44 ea 74 5a df ee a0 8d 5c 6e c9 14 34 7c d1 b5 62 7d be a2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}