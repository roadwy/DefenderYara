
rule Trojan_Win32_VBInject_CD_MTB{
	meta:
		description = "Trojan:Win32/VBInject.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b cb 8d 04 11 8b 4d b8 66 8b 1c 79 66 03 1c 71 66 83 e3 0f 79 ?? 66 4b 66 83 cb f0 66 43 0f bf db 8a 0c 59 8a 18 32 d9 88 18 8b 85 6c ff ff ff 03 d0 e9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}