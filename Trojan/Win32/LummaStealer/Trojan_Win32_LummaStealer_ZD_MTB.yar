
rule Trojan_Win32_LummaStealer_ZD_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZD!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6b 2c 0d 68 2a 07 0d 4c 8b 67 09 cd 2d e8 4c 2c 27 ac 4c 0d 0b ac c7 67 2b ac 4c 6d c9 08 8a 6c 89 0c e6 8d c8 66 28 2c 8b 0c 29 c8 47 4b aa 86 ab 48 0b 86 ac 68 8a cc 07 ac 0c c7 28 a8 66 67 2b 28 c9 2d e8 aa 8d a9 eb ad e6 ec 4a cb 2d ed 0d 0c a7 ac a7 45 07 aa ac 0d 4c 88 2a 47 ca 09 6b 2d 45 87 69 ab 4e 07 c9 29 cc a7 cb e7 aa 45 ec 6c ea ac 0c a8 45 ea c8 86 8d 08 29 27 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}