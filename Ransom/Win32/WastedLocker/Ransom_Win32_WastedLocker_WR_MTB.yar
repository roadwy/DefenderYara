
rule Ransom_Win32_WastedLocker_WR_MTB{
	meta:
		description = "Ransom:Win32/WastedLocker.WR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 1f 4d 8a cb 47 e8 ?? ?? ff ff 0f b6 c8 0f b6 d3 83 e1 0f c1 ea 04 33 ca c1 e8 04 33 04 8e 85 ed 75 } //1
		$a_01_1 = {33 c8 83 e1 0f c1 e8 04 33 04 8a c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}