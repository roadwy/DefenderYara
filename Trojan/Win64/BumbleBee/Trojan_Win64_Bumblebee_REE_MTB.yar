
rule Trojan_Win64_Bumblebee_REE_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.REE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 8b d1 48 8b 05 16 0a 05 00 c1 ea 08 ff 40 40 48 8b 43 78 48 63 0d 55 0a 05 00 88 14 01 b8 cd b3 09 00 ff 05 47 0a 05 00 2b 83 14 01 00 00 2b 83 90 00 00 00 01 83 fc 00 00 00 48 8b 43 78 48 63 0d 2a 0a 05 00 44 88 0c 01 ff 05 20 0a 05 00 48 8b 15 c9 09 05 00 8b 4a 34 33 8b d0 00 00 00 8b 82 f0 00 00 00 81 e9 5d 32 12 00 0f af c1 89 82 f0 00 00 00 b8 87 f3 02 00 2b 43 28 01 05 7d 0a 05 00 8b 83 90 00 00 00 33 c6 29 83 14 01 00 00 49 81 fb 80 29 00 00 7d 0c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}