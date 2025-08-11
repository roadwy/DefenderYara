
rule Trojan_Win32_LummaStealer_ZI_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZI!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0d 57 c6 ad 0c 72 de f9 c5 91 52 8f 25 8a 03 67 15 ec 15 f5 d1 76 08 62 93 c4 7f 1a 80 60 f6 7f 34 f4 3a 14 a5 ae 69 b7 8a 2f 82 e1 e2 1f 91 1d ee 7d 22 4d 47 db 17 11 a2 91 04 32 51 a2 6a b0 76 5b 97 49 c5 bc 5e 05 99 18 42 8e 38 a3 55 e1 37 a0 9d a9 fc bd 2b bc 10 77 51 fd 8f ac e5 f4 42 9b 9f ec 69 3c 98 90 24 ae 71 98 c1 2a 55 d6 a7 f9 ae 73 4c bd 73 bb f4 7f 7a ae 58 90 bf 45 33 5c 56 ce 40 a3 80 5d 92 a9 bb 3b 99 39 71 cf bf 44 13 2e 93 f2 5f d3 8d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}