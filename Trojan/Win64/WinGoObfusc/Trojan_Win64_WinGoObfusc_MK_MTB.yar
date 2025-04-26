
rule Trojan_Win64_WinGoObfusc_MK_MTB{
	meta:
		description = "Trojan:Win64/WinGoObfusc.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 ff c3 8b 5c 24 20 c1 eb 18 0f b6 db 45 8b 0c 9f 46 33 4c a0 0c c1 ef 08 8b 5c 24 10 0f b6 db 44 8b 6c 24 28 41 c1 ed 10 40 0f b6 ff 45 0f b6 ed 46 33 0c ae 45 33 0c b8 45 33 0c 9a 49 8d 5c 24 04 48 8b 7c 24 30 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}