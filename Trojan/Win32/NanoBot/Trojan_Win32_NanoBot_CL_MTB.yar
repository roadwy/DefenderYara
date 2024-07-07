
rule Trojan_Win32_NanoBot_CL_MTB{
	meta:
		description = "Trojan:Win32/NanoBot.CL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 8d 38 ff ff ff 83 c1 90 01 01 89 8d 38 ff ff ff 8b 55 ac 0f b7 42 06 39 85 38 ff ff ff 7d 90 01 01 8b 8d 70 ff ff ff 8b 95 70 ff ff ff 8b b5 54 ff ff ff 03 72 14 8b 85 70 ff ff ff 8b 7d f4 03 78 0c 8b 49 10 f3 a4 8b 8d 70 ff ff ff 83 c1 28 89 8d 70 ff ff ff eb 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}