
rule Trojan_Win32_Agent_AFA{
	meta:
		description = "Trojan:Win32/Agent.AFA,SIGNATURE_TYPE_PEHSTR,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {bf cd bb a7 b6 cb ba cd b7 fe ce f1 c6 f7 d6 ae bc e4 b5 c4 20 4e 45 54 20 53 45 4e 44 20 ba cd 20 41 6c 65 72 74 65 72 20 b7 fe ce f1 cf fb cf a2 a1 a3 b4 cb b7 fe ce f1 d3 eb 20 57 69 6e 64 6f 77 73 20 4d 65 73 73 65 6e 67 65 72 20 ce de b9 d8 a1 a3 c8 e7 b9 fb b7 fe ce f1 cd a3 d6 b9 a3 ac 41 6c 65 72 74 65 72 20 cf fb cf a2 b2 bb bb e1 b1 bb b4 ab ca e4 a1 a3 c8 e7 b9 fb b7 fe ce f1 b1 bb bd fb d3 c3 a3 ac c8 ce ba ce d6 b1 bd d3 d2 c0 c0 b5 d3 da b4 cb b7 fe ce f1 b5 c4 b7 fe ce f1 bd ab ce de b7 a8 c6 f4 b6 af a1 a3 } //10
		$a_01_1 = {64 6f 73 2e 68 61 6f 77 61 6e 31 2e 63 6f 6d } //5 dos.haowan1.com
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}