
rule Trojan_Win32_FlyStudio_AT_MTB{
	meta:
		description = "Trojan:Win32/FlyStudio.AT!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 42 e8 67 67 e6 ac 04 04 c4 c4 c4 47 8c 9b 2c 96 a6 a5 d6 28 48 48 48 e9 e9 54 e7 15 cb c3 89 68 4c 42 96 67 67 67 49 78 c4 6f 6f 6f 78 e0 7f db 05 23 7e b5 5d 5d 65 1f 84 66 72 c2 8c 09 2b 3c 9e 42 96 67 67 67 f4 35 1c 78 2a 2a 78 44 cd 10 85 1d 05 db 05 23 7e 5d 84 66 ff 1d 15 09 cf 48 ef 42 96 67 67 67 49 ce bf bf bf 2a 44 87 88 19 10 8e 8e 10 7f 23 34 62 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}