
rule Trojan_Win32_Azorult_NO_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 81 ec [0-04] a1 [0-04] 33 ?? 89 45 fc 56 33 f6 85 ff 7e 3d 8d [0-05] e8 [0-04] 30 [0-02] 83 [0-02] 90 18 46 3b f7 7c } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}