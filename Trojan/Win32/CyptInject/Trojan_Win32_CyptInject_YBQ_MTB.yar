
rule Trojan_Win32_CyptInject_YBQ_MTB{
	meta:
		description = "Trojan:Win32/CyptInject.YBQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 95 44 f3 ff ff 83 c2 01 89 95 44 f3 ff ff 8b 85 44 f3 ff ff 3b 85 f8 ed ff ff 73 ?? 53 81 cb fb 7a 01 00 81 f3 } //2
		$a_01_1 = {81 c8 2a 38 01 00 58 0f b6 8d 97 f9 ff ff 8b 95 44 f3 ff ff 0f be 02 2b c1 8b 8d 44 f3 ff ff 88 01 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}